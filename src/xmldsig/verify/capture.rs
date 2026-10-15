//! Original execution facts retained only by scoped verification.

use super::*;
use structured_asn1::memory::{MemoryError, OwnedMap, OwnedVec, Work};

/// Original parsed method, not a reconstruction from an algorithm URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedSignatureMethod {
    /// Original SignatureMethod node, including document generation.
    pub identity: NodeIdentity,
    /// Parsed signature algorithm, including effective RSA-PSS parameters.
    pub algorithm: SignatureAlgorithm,
}

pub(super) trait VerificationCapture {
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
}

impl VerificationCapture for () {}

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
            failure: Cell::new(None),
            work,
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
