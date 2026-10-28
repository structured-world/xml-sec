//! Original execution facts retained only by scoped verification.

use super::{
    Cell, DigestAlgorithm, DocumentView, DsigError, KeyInfo, KeyInfoOrigin, KeyInfoReading, Node,
    NodeId, NodeIdentity, OperationExecutionContext, RefCell, SignatureAlgorithm, SourceOrigin,
    VerifyingKey, XMLDSIG_NS,
};
use crate::xmldsig::parse::{KeyInfoSource, KeyValueInfo};
use structured_asn1::memory::{MemoryError, MemoryReservation, OwnedMap, OwnedVec, Work};

/// Original parsed method, not a reconstruction from an algorithm URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedSignatureMethod {
    /// Original `SignatureMethod` node, including document generation.
    pub identity: NodeIdentity,
    /// Parsed signature algorithm, including effective RSA-PSS parameters.
    pub algorithm: SignatureAlgorithm,
}

pub(super) trait VerificationCapture {
    /// Whether [`Self::key_info`] keeps the candidates, so verification tracks
    /// each source's element while materializing `KeyInfo`.
    const RETAINS_KEY_INFO: bool = false;

    fn verify(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        key: &dyn VerifyingKey,
        input: crate::provider::SignatureVerificationInput<'_>,
    ) -> Result<bool, DsigError> {
        provider.verify_with_context(
            key,
            input.algorithm,
            input.context,
            input.data,
            input.signature,
        )
    }
    fn method(
        &self,
        _view: DocumentView<'_>,
        _signed_info: Node<'_, '_>,
        _algorithm: SignatureAlgorithm,
    ) -> Result<(), MemoryError> {
        Ok(())
    }
    fn admit_digest(
        &self,
        _reference: Option<NodeId>,
        _algorithm: DigestAlgorithm,
    ) -> Result<(), MemoryError> {
        Ok(())
    }
    fn computed_digest(&self, _reference: Option<NodeId>) -> Result<(), MemoryError> {
        Ok(())
    }
    /// The authenticated Signature's `KeyInfo` as key selection consumed it.
    /// `origins` is present only when [`Self::RETAINS_KEY_INFO`] is set.
    fn key_info(
        &self,
        _view: DocumentView<'_>,
        _reading: KeyInfoReading,
        _key_info: Option<KeyInfo>,
        _origins: Option<Vec<SourceOrigin>>,
    ) -> Result<(), MemoryError> {
        Ok(())
    }
}

impl VerificationCapture for () {}

/// Key material a verified Signature's `KeyInfo` offered, moved from parsing.
pub(super) enum RetainedMaterial {
    Certificate(Vec<u8>),
    KeyValue(KeyValueInfo),
    SubjectPublicKeyInfo(Vec<u8>),
    Unmaterialized {
        uri: String,
        resource_type: Option<String>,
    },
}

impl RetainedMaterial {
    /// Heap bytes this material keeps alive.
    fn capacity(&self) -> Result<usize, MemoryError> {
        fn sum(sizes: &[usize]) -> Result<usize, MemoryError> {
            sizes.iter().try_fold(0usize, |total, size| {
                total
                    .checked_add(*size)
                    .ok_or(MemoryError::CapacityOverflow)
            })
        }
        let vector = |value: &Option<Vec<u8>>| value.as_ref().map_or(0, Vec::capacity);
        match self {
            Self::Certificate(der) | Self::SubjectPublicKeyInfo(der) => Ok(der.capacity()),
            Self::KeyValue(KeyValueInfo::Rsa { modulus, exponent }) => {
                sum(&[modulus.capacity(), exponent.capacity()])
            }
            Self::KeyValue(KeyValueInfo::Dsa { p, q, g, y }) => {
                sum(&[vector(p), vector(q), vector(g), y.capacity()])
            }
            Self::KeyValue(KeyValueInfo::Dh {
                p,
                q,
                generator,
                public,
                seed,
                pgen_counter,
            }) => sum(&[
                vector(p),
                vector(q),
                vector(generator),
                public.capacity(),
                vector(seed),
                vector(pgen_counter),
            ]),
            Self::KeyValue(KeyValueInfo::Ec {
                curve_oid,
                public_key,
            }) => sum(&[curve_oid.capacity(), public_key.capacity()]),
            Self::KeyValue(KeyValueInfo::Unsupported {
                namespace,
                local_name,
            }) => sum(&[
                namespace.as_ref().map_or(0, String::capacity),
                local_name.capacity(),
            ]),
            Self::KeyValue(KeyValueInfo::InvalidEcKeyValue) => Ok(0),
            Self::Unmaterialized { uri, resource_type } => sum(&[
                uri.capacity(),
                resource_type.as_ref().map_or(0, String::capacity),
            ]),
        }
    }
}

/// One candidate with the reservation accounting for its moved material.
/// Fields drop in order: the material is freed before its charge is released.
pub(super) struct RetainedCandidate {
    pub(super) origin: KeyInfoOrigin,
    pub(super) material: RetainedMaterial,
    _reservation: MemoryReservation,
}

pub(super) struct RetainedKeyInfo<W: Work> {
    pub(super) reading: KeyInfoReading,
    pub(super) candidates: OwnedVec<RetainedCandidate, W>,
}

#[derive(Clone, Copy)]
pub(super) struct CapturedDigest {
    pub(super) algorithm: DigestAlgorithm,
    pub(super) computed: bool,
}

pub(super) struct ScopedCapture<'work, W: Work> {
    pub(super) seal: [u8; 1],
    pub(super) key: RefCell<CapturedKey<W>>,
    pub(super) method: Cell<Option<SelectedSignatureMethod>>,
    // Arena ordinals are private to the retained original operation, never
    // compared across parses or exposed as public provenance.
    pub(super) digests: RefCell<OwnedMap<usize, CapturedDigest, W>>,
    // Set once, for an authenticated Signature only.
    pub(super) key_info: RefCell<Option<RetainedKeyInfo<W>>>,
    pub(super) failure: Cell<Option<MemoryError>>,
    work: &'work W,
}

pub(super) struct CapturedKey<W: Work> {
    pub(super) public: Option<OwnedVec<u8, W>>,
    pub(super) binding: Option<crate::provider::ProviderBinding>,
    observations: u8,
}

impl<'work, W: Work> ScopedCapture<'work, W> {
    pub(super) fn new(work: &'work W) -> Self {
        Self {
            seal: [0],
            key: RefCell::new(CapturedKey {
                public: None,
                binding: None,
                observations: 0,
            }),
            method: Cell::new(None),
            digests: RefCell::new(work.map()),
            key_info: RefCell::new(None),
            failure: Cell::new(None),
            work,
        }
    }

    /// Move one material into accounted retention: the reservation covers the
    /// capacity the material keeps alive, so no byte is copied.
    fn retain_material(
        &self,
        candidates: &mut OwnedVec<RetainedCandidate, W>,
        origin: KeyInfoOrigin,
        material: RetainedMaterial,
    ) -> Result<(), MemoryError> {
        let reservation = self.work.memory().reserve(material.capacity()?)?;
        candidates.try_push(RetainedCandidate {
            origin,
            material,
            _reservation: reservation,
        })
    }

    fn retain_source(
        &self,
        view: DocumentView<'_>,
        candidates: &mut OwnedVec<RetainedCandidate, W>,
        source: KeyInfoSource,
        origin: SourceOrigin,
    ) -> Result<(), MemoryError> {
        let (element, retrieved) = match origin {
            SourceOrigin::Element(node) => (node, None),
            SourceOrigin::Retrieved(node) => (
                node,
                Some(KeyInfoOrigin::Retrieved(view.node_identity_by_id(node))),
            ),
        };
        let own = || retrieved.unwrap_or(KeyInfoOrigin::Element(view.node_identity_by_id(element)));
        match source {
            KeyInfoSource::X509Data(info) => {
                // The parser keeps one certificate per X509Certificate child,
                // in document order; each certificate names its own element.
                let node = view
                    .document()
                    .get_node(element)
                    .expect("retained KeyInfo source belongs to the verified document");
                let mut elements = node
                    .children()
                    .filter(|child| child.has_tag_name((XMLDSIG_NS, "X509Certificate")));
                for der in info.certificates {
                    self.work.charge_work(1)?;
                    let origin = retrieved.unwrap_or_else(|| {
                        let certificate = elements
                            .next()
                            .expect("one X509Certificate element per parsed certificate");
                        KeyInfoOrigin::Element(view.node_identity(certificate))
                    });
                    self.retain_material(candidates, origin, RetainedMaterial::Certificate(der))?;
                }
                Ok(())
            }
            KeyInfoSource::KeyValue(value) => {
                self.retain_material(candidates, own(), RetainedMaterial::KeyValue(value))
            }
            KeyInfoSource::DerEncodedKeyValue(der) => self.retain_material(
                candidates,
                own(),
                RetainedMaterial::SubjectPublicKeyInfo(der),
            ),
            KeyInfoSource::RetrievalMethod {
                uri, resource_type, ..
            } => self.retain_material(
                candidates,
                own(),
                RetainedMaterial::Unmaterialized { uri, resource_type },
            ),
            // A name selects caller-held material; KeyInfo offers none itself.
            // References are expanded or refused before key selection.
            KeyInfoSource::KeyName(_) | KeyInfoSource::KeyInfoReference { .. } => Ok(()),
        }
    }

    fn retain_failure<T>(&self, result: Result<T, MemoryError>) -> Result<T, MemoryError> {
        if let Err(error) = result
            && self.failure.get().is_none()
        {
            self.failure.set(Some(error));
        }
        result
    }

    fn copy_public_evidence(&self, public: &[u8]) -> Result<OwnedVec<u8, W>, MemoryError> {
        let mut bytes = self.work.vector();
        // OwnedVec admits public.len() copy work before reserving capacity;
        // its allocator separately admits allocation work before allocation.
        // A separate byte charge here would bill the same copy twice; retain
        // its original refusal so candidate recovery cannot erase it.
        self.retain_failure(bytes.try_extend_from_slice(public))?;
        Ok(bytes)
    }
}

impl<W: Work> VerificationCapture for ScopedCapture<'_, W> {
    const RETAINS_KEY_INFO: bool = true;

    fn key_info(
        &self,
        view: DocumentView<'_>,
        reading: KeyInfoReading,
        key_info: Option<KeyInfo>,
        origins: Option<Vec<SourceOrigin>>,
    ) -> Result<(), MemoryError> {
        self.retain_failure((|| {
            let mut candidates = self.work.vector();
            if let (Some(key_info), Some(origins)) = (key_info, origins) {
                debug_assert_eq!(key_info.sources.len(), origins.len());
                for (source, origin) in key_info.sources.into_iter().zip(origins) {
                    self.retain_source(view, &mut candidates, source, origin)?;
                }
            }
            *self.key_info.borrow_mut() = Some(RetainedKeyInfo {
                reading,
                candidates,
            });
            Ok(())
        })())
    }

    fn verify(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        key: &dyn VerifyingKey,
        input: crate::provider::SignatureVerificationInput<'_>,
    ) -> Result<bool, DsigError> {
        let result = provider.verify_with_key_receipt(key, input, &mut |event| {
            if let Some(error) = self.failure.get() {
                return Err(error.into());
            }
            if matches!(event, crate::provider::KeyVerificationEvent::BeforeCandidate { depth }
                if depth == crate::hard_limits::KEY_CANDIDATE_CEILING)
            {
                return self
                    .retain_failure(Err(MemoryError::WorkExceeded))
                    .map_err(Into::into);
            }
            self.retain_failure(self.work.charge_work(1))?;
            let crate::provider::KeyVerificationEvent::Verified(key) = event else {
                return Ok(());
            };
            let mut retained = self.key.borrow_mut();
            if retained.observations != 0 {
                // A custom composite that continues after success supplies no
                // unique winning leaf. Never pick an arbitrary success for it.
                retained.observations = 2;
                retained.public = None;
                retained.binding = None;
                return Ok(());
            }
            retained.observations = 1;
            if let Some(public) = key.association_spki(input.algorithm) {
                retained.public = Some(self.copy_public_evidence(public)?);
            }
            retained.binding = key.provider_binding().cloned();
            Ok(())
        });
        if let Some(error) = self.failure.get() {
            return Err(error.into());
        }
        result
    }
    fn method(
        &self,
        view: DocumentView<'_>,
        signed_info: Node<'_, '_>,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), MemoryError> {
        self.retain_failure((|| {
            for child in signed_info.children() {
                self.work.charge_work(64)?;
                if child.has_tag_name((XMLDSIG_NS, "SignatureMethod")) {
                    self.method.set(Some(SelectedSignatureMethod {
                        identity: view.node_identity(child),
                        algorithm,
                    }));
                    break;
                }
            }
            Ok(())
        })())
    }

    fn admit_digest(
        &self,
        reference: Option<NodeId>,
        algorithm: DigestAlgorithm,
    ) -> Result<(), MemoryError> {
        self.retain_failure((|| {
            if let Some(reference) = reference {
                self.digests.borrow_mut().try_insert(
                    reference.get_usize(),
                    CapturedDigest {
                        algorithm,
                        computed: false,
                    },
                )?;
            }
            Ok(())
        })())
    }

    fn computed_digest(&self, reference: Option<NodeId>) -> Result<(), MemoryError> {
        self.retain_failure((|| {
            if let Some(reference) = reference {
                let mut digests = self.digests.borrow_mut();
                let completed = digests
                    .get_mut(&reference.get_usize(), self.work)?
                    .expect("digest admitted before execution");
                completed.computed = true;
            }
            Ok(())
        })())
    }
}

pub(super) struct CapturedOperation<P, B, C> {
    pub(super) operation: OperationExecutionContext<P, B>,
    pub(super) capture: C,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};

    #[test]
    fn receipt_copy_charges_exact_byte_work_before_capacity_and_stays_terminal() {
        // The bounded vector, not merely its observer event, pays every copied
        // byte exactly once. An insufficient budget must leave no retained copy.
        let public = vec![0x42; 128 * 1024];
        let exact = public.len() * 2; // One byte-copy pass plus one allocation.
        for allowance in [public.len() - 1, exact - 1, exact] {
            let work = Memory::new(Arc::new(MemoryAccount::new(public.len() * 2, allowance)));
            let capture = ScopedCapture::new(&work);
            let result = capture.copy_public_evidence(&public);
            if allowance < exact {
                assert!(matches!(result, Err(MemoryError::WorkExceeded)));
                assert_eq!(work.used(), 0);
                assert_eq!(capture.failure.get(), Some(MemoryError::WorkExceeded));
                let _ = capture.retain_failure(Err::<(), _>(MemoryError::LimitExceeded));
                assert_eq!(capture.failure.get(), Some(MemoryError::WorkExceeded));
            } else {
                let copied = match result {
                    Ok(copied) => copied,
                    Err(error) => panic!("exact admitted copy failed: {error:?}"),
                };
                assert_eq!(&*copied, public.as_slice());
                assert_eq!(work.work_used(), exact);
                drop(copied);
                assert_eq!(work.used(), 0);
            }
        }
    }

    #[test]
    fn first_receipt_resource_failure_stays_terminal() {
        // Manifest recovery must not replace an earlier allocator/capacity
        // cause with a later work error while continuing other instructions.
        let work = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
        let capture = ScopedCapture::new(&work);
        assert!(
            capture
                .retain_failure(Err::<(), _>(MemoryError::LimitExceeded))
                .is_err()
        );
        assert!(
            capture
                .retain_failure(Err::<(), _>(MemoryError::WorkExceeded))
                .is_err()
        );
        assert_eq!(capture.failure.get(), Some(MemoryError::LimitExceeded));
    }
}
